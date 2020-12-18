/** @file
 * svi2-dec - AMD SVI2 protocol decoder from a Saleae Logic analyzer capture.
 */

/*
 * Copyright (C) 2020 Alexander Eichner <alexander.eichner@campus.tu-berlin.de>
 *
 * This program is free software: you can redistribute it and/or modify  
 * it under the terms of the GNU General Public License as published by  
 * the Free Software Foundation, version 3.
 *
 * This program is distributed in the hope that it will be useful, but 
 * WITHOUT ANY WARRANTY; without even the implied warranty of 
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU 
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License 
 * along with this program. If not, see <http://www.gnu.org/licenses/>.
 */

/** @page pg_svi2_dev   SVI2 - AMD SVI2 protocol decoder
 *
 * The protocol specification is not public but datasheets for the ISL62776 and IR35201 revealed enough
 * information to implement a simple decoder.
 *     IR35201:  https://www.infineon.com/dgdl/Infineon-IR35201MTRPBF-DS-v01_00-EN.pdf?fileId=5546d462576f347501579c95d19772b5
 *     ISL62776: https://www.renesas.com/br/ja/document/dst/isl62776-datasheet
 */


/*********************************************************************************************************************************
*   Header Files                                                                                                                 *
*********************************************************************************************************************************/

#include <getopt.h>
#include <inttypes.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>


/*********************************************************************************************************************************
*   Defined Constants And Macros                                                                                                 *
*********************************************************************************************************************************/


/*********************************************************************************************************************************
*   Structures and Typedefs                                                                                                      *
*********************************************************************************************************************************/


/**
 * File buffered reader.
 */
typedef struct SVI2DECFILEBUFREAD
{
    /** The file handle. */
    FILE                        *pFile;
    /** Current amount of data in the buffer. */
    size_t                      cbData;
    /** Where to read next from the buffer. */
    uint32_t                    offBuf;
    /** Error flag. */
    uint8_t                     fError;
    /** Eos flag. */
    uint8_t                     fEos;
    /** Buffered data. */
    uint8_t                     abBuf[64 * 1024];
} SVI2DECFILEBUFREAD;
/** Pointer to a file buffered reader. */
typedef SVI2DECFILEBUFREAD *PSVI2DECFILEBUFREAD;
/** Pointer to a const file buffered reader. */
typedef const SVI2DECFILEBUFREAD *PCSVI2DECFILEBUFREAD;


/**
 * Current SVI2 decoder state.
 */
typedef enum SVI2DECSTATE
{
    /** Invalid state, do not use. */
    SVI2DECSTATE_INVALID = 0,
    /** Waiting for the start condition to appear. */
    SVI2DECSTATE_WAIT_START,
    /** Byte gets transmitted. */
    SVI2DECSTATE_BYTE,
    /** ACK phase. */
    SVI2DECSTATE_ACK,
    /** STOP signal. */
    SVI2DECSTATE_STOP,
    /** 32bit hack. */
    SVI2DECSTATE_32BIT_HACK = 0x7fffffff
} SVI2DECSTATE;


/**
 * SVI2 decoder state.
 */
typedef struct SVI2DEC
{
    /** Bit number for the SVC signal. */
    uint8_t                     u8BitSvc;
    /** Bit number for the SVD signal. */
    uint8_t                     u8BitSvd;
    /** Bit number for the SVT. */
    uint8_t                     u8BitSvt;
    /** The next state to write into. */
    uint32_t                    idxState;
    /** Current decoder state. */
    SVI2DECSTATE                enmState;
    /** Sequence number when the cycle started. */
    uint64_t                    uSeqNoCycle;
    /** Last clock value seen. */
    uint8_t                     fClkLast;
    /** Last SVD value seen. */
    uint8_t                     fSvdLast;
    /** Number of bits left to receive for the current byte. */
    uint8_t                     cBitsLeft;
    /** Current byte being received. */
    uint8_t                     idxData;
    /** The data being consturcted during the data phase. */
    uint8_t                     abData[3];
} SVI2DEC;
/** Pointer to a SVI2 decoder state. */
typedef SVI2DEC *PSVI2DEC;
/** Pointer to a const SVI2 decoder state. */
typedef const SVI2DEC *PCSVI2DEC;


/*********************************************************************************************************************************
*   Global Variables                                                                                                             *
*********************************************************************************************************************************/

/** Flag whether verbose mode is enabled. */
static uint8_t g_fVerbose = 0;

/**
 * Available options for lpc-dec.
 */
static struct option g_aOptions[] =
{
    {"input",   required_argument, 0, 'i'},
    {"verbose", no_argument,       0, 'v'},

    {"help",    no_argument,       0, 'H'},
    {0, 0, 0, 0}
};


/**
 * Load line slope trim values.
 */
static const char *g_apszLdLineSlopeTrim[] =
{
    "Disable LL",
    "-40% mOhm",
    "-20% mOhm",
    "No Change",
    "+20% mOhm",
    "+40% mOhm",
    "+60% mOhm",
    "+80% mOhm"
};


/**
 * Dynamic offset trim values.
 */
static const char *g_apszOffTrim[] =
{
    "Disable All Offset",
    "-25mV change",
    "0mV change",
    "+25mV change",
};


/**
 * VID code to voltage (in uV).
 */
static uint32_t g_au32VidCode2UV[256] =
{
    /*0x00     0x01     0x02     0x03     0x04     0x05     0x06     0x07     0x08     0x09     0x0a     0x0b     0x0c     0x0d     0x0e     0x0f  */
    1550000, 1543750, 1537500, 1531250, 1525000, 1518750, 1512500, 1506250, 1500000, 1493750, 1487500, 1481250, 1475000, 1468750, 1462500, 1456250,
    /*0x10     0x11     0x12     0x13     0x14     0x15     0x16     0x17     0x18     0x19     0x1a     0x1b     0x1c     0x1d     0x1e     0x1f  */
    1450000, 1443750, 1437500, 1431250, 1425000, 1418750, 1412500, 1406250, 1400000, 1393750, 1387500, 1381250, 1375000, 1368750, 1362500, 1356250,
    /*0x20     0x21     0x22     0x23     0x24     0x25     0x26     0x27     0x28     0x29     0x2a     0x2b     0x2c     0x2d     0x2e     0x2f  */
    1350000, 1343750, 1337500, 1331250, 1325000, 1318750, 1312500, 1306250, 1200000, 1293750, 1287500, 1281250, 1275000, 1268750, 1262500, 1256250,
    /*0x30     0x31     0x32     0x33     0x34     0x35     0x36     0x37     0x38     0x39     0x3a     0x3b     0x3c     0x3d     0x3e     0x3f  */
    1250000, 1243750, 1237500, 1231250, 1225000, 1218750, 1212500, 1206250, 1200000, 1193750, 1187500, 1181250, 1175000, 1168750, 1162500, 1156250,
    /*0x40     0x41     0x42     0x43     0x44     0x45     0x46     0x47     0x48     0x49     0x4a     0x4b     0x4c     0x4d     0x4e     0x4f  */
    1150000, 1143750, 1137500, 1131250, 1125000, 1118750, 1112500, 1106250, 1100000, 1093750, 1087500, 1081250, 1075000, 1068750, 1062500, 1056250,
    /*0x50     0x51     0x52     0x53     0x54     0x55     0x56     0x57     0x58     0x59     0x5a     0x5b     0x5c     0x5d     0x5e     0x5f  */
    1050000, 1043750, 1037500, 1031250, 1025000, 1008750, 1012500, 1006250, 1000000,  993750,  987500,  981250,  975000,  968750,  962500,  956250,
    /*0x60     0x61     0x62     0x63     0x64     0x65     0x66     0x67     0x68     0x69     0x6a     0x6b     0x6c     0x6d     0x6e     0x6f  */
     950000,  943750,  937500,  931250,  925000,  918750,  912500,  906250,  900000,  893750,  887500,  881250,  875000,  868750,  862500,  856250,
    /*0x70     0x71     0x72     0x73     0x74     0x75     0x76     0x77     0x78     0x79     0x7a     0x7b     0x7c     0x7d     0x7e     0x7f  */
     850000,  843750,  837500,  831250,  825000,  818750,  812500,  806250,  800000,  793750,  787500,  781250,  775000,  768750,  762500,  756250,
    /*0x80     0x81     0x82     0x83     0x84     0x85     0x86     0x87     0x88     0x89     0x8a     0x8b     0x8c     0x8d     0x8e     0x8f  */
     750000,  743750,  737500,  731250,  725000,  718750,  712500,  706250,  700000,  693750,  687500,  681250,  675000,  668750,  662500,  656250,
    /*0x90     0x91     0x92     0x93     0x94     0x95     0x96     0x97     0x98     0x99     0x9a     0x9b     0x9c     0x9d     0x9e     0x9f  */
     650000,  643750,  637500,  631250,  625000,  618750,  612500,  606250,  600000,  593750,  587500,  581250,  575000,  568750,  562500,  556250,
    /*0xa0     0xa1     0xa2     0xa3     0xa4     0xa5     0xa6     0xa7     0xa8     0xa9     0xaa     0xab     0xac     0xad     0xae     0xaf  */
     550000,  543750,  537500,  531250,  525000,  518750,  512500,  506250,  500000,  493750,  487500,  481250,  475000,  468750,  462500,  456250,
    /*0xb0     0xb1     0xb2     0xb3     0xb4     0xb5     0xb6     0xb7     0xb8     0xb9     0xba     0xbb     0xbc     0xbd     0xbe     0xbf  */
     450000,  443750,  437500,  431250,  425000,  418750,  412500,  406250,  400000,  393750,  387500,  381250,  375000,  368750,  362500,  356250,
    /*0xc0     0xc1     0xc2     0xc3     0xc4     0xc5     0xc6     0xc7     0xc8     0xc9     0xca     0xcb     0xcc     0xcd     0xce     0xcf  */
     350000,  343750,  337500,  331250,  325000,  318750,  312500,  306250,  300000,  293750,  287500,  281250,  275000,  268750,  262500,  256250,
    /*0xd0     0xd1     0xd2     0xd3     0xd4     0xd5     0xd6     0xd7     0xd8     0xd9     0xda     0xdb     0xdc     0xdd     0xde     0xdf  */
     250000,  243750,  237500,  231250,  225000,  218750,  212500,  206250,  200000,  193750,  187500,  181250,  175000,  168750,  162500,  156250,
    /*0xe0     0xe1     0xe2     0xe3     0xe4     0xe5     0xe6     0xe7     0xe8     0xe9     0xea     0xeb     0xec     0xed     0xee     0xef  */
     150000,  143750,  137500,  131250,  125000,  118750,  112500,  106250,  100000,   93750,   87500,   81250,   75000,   68750,   62500,   56250,
    /*0xf0     0xf1     0xf2     0xf3     0xf4     0xf5     0xf6     0xf7     0xf8     0xf9     0xfa     0xfb     0xfc     0xfd     0xfe     0xff  */
      50000,   43750,   37500,   31250,   25000,   18750,   12500,    6250,       0,       0,      0,       0,       0,       0,       0,       0
};


/*********************************************************************************************************************************
*   Internal Functions                                                                                                           *
*********************************************************************************************************************************/


/**
 * Creates a new buffered file reader from the given filename.
 *
 * @returns Status code.
 * @param   ppBufFile               Where to store the pointer to the buffered file reader on success.
 * @param   pszFilename             The file to load.
 */
static int svi2DecFileBufReaderCreate(PSVI2DECFILEBUFREAD *ppBufFile, const char *pszFilename)
{
    int rc = 0;
    FILE *pFile = fopen(pszFilename, "rb");
    if (pFile)
    {
        PSVI2DECFILEBUFREAD pBufFile = (PSVI2DECFILEBUFREAD)calloc(1, sizeof(*pBufFile));
        if (pBufFile)
        {
            pBufFile->pFile  = pFile;
            pBufFile->cbData = 0;
            pBufFile->offBuf = 0;
            pBufFile->fError = 0;
            pBufFile->fEos   = 0;

            /* Read in the first chunk. */
            size_t cbRead = fread(&pBufFile->abBuf[0], 1, sizeof(pBufFile->abBuf), pFile);
            if (cbRead)
            {
                pBufFile->cbData = cbRead;
                *ppBufFile = pBufFile;
                return 0;
            }
            else
                rc = -1;
        }
        else
            rc = -1;

        fclose(pFile);
    }
    else
        rc = errno;

    return rc;
}


/**
 * Closes the given buffered file reader.
 *
 * @returns nothing.
 * @param   pBufFile                The buffered file reader to close.
 */
static void svi2DecFileBufReaderClose(PSVI2DECFILEBUFREAD pBufFile)
{
    fclose(pBufFile->pFile);
    free(pBufFile);
}


/**
 * Returns whether the given buffered file reader has run into an error.
 *
 * @returns Flag whether the has run into an error.
 * @param   pBufFile                The buffered file reader to check.
 */
static inline uint8_t svi2DecFileBufReaderHasError(PCSVI2DECFILEBUFREAD pBufFile)
{
    return pBufFile->fError;
}


/**
 * Returns whether the given buffered file reader has reached EOS.
 *
 * @returns Flag whether the has reached EOS.
 * @param   pBufFile                The buffered file reader to check.
 */
static inline uint8_t svi2DecFileBufReaderHasEos(PCSVI2DECFILEBUFREAD pBufFile)
{
    return pBufFile->fEos;
}


/**
 * Ensures that there is enough data to read.
 *
 * @returns Status code.
 * @param   pBufFile                The buffered file reader.
 * @param   cbData                  Amount of bytes which should be available.
 */
static int svi2DecFileBufReaderEnsureData(PSVI2DECFILEBUFREAD pBufFile, size_t cbData)
{
    if (pBufFile->offBuf + cbData <= pBufFile->cbData)
        return 0;

    /* Move all the remaining data to the front and fill up the free space. */
    size_t cbRem = pBufFile->cbData - pBufFile->offBuf;
    memmove(&pBufFile->abBuf[0], &pBufFile->abBuf[pBufFile->offBuf], cbRem);

    /* Try reading in more data. */
    size_t cbRead = fread(&pBufFile->abBuf[cbRem], 1, sizeof(pBufFile->abBuf) - cbRem, pBufFile->pFile);
    pBufFile->cbData = cbRead + cbRem;
    pBufFile->offBuf = 0;
    if (!cbRead)
        pBufFile->fEos = 1;

    return 0;
}


/**
 * Returns the next byte from the given buffered file reader.
 *
 * @returns Next byte value (0xff on error and error condition needs to get checked using svi2DecFileBufReaderHasError()).
 * @param   pBufFile                The buffered file reader.
 */
static uint8_t svi2DecFileBufReaderGetU8(PSVI2DECFILEBUFREAD pBufFile)
{
    /* Ensure that there is no error and there is least one byte to read. */
    if (   svi2DecFileBufReaderHasError(pBufFile)
        || svi2DecFileBufReaderEnsureData(pBufFile, sizeof(uint8_t)))
        return UINT8_MAX;

    return pBufFile->abBuf[pBufFile->offBuf++];
}


/**
 * Returns the next 64bit unsigned integer from the given buffered file reader.
 *
 * @returns Next byte value (0xff on error and error condition needs to get checked using svi2DecFileBufReaderHasError()).
 * @param   pBufFile                The buffered file reader.
 */
static uint64_t svi2DecFileBufReaderGetU64(PSVI2DECFILEBUFREAD pBufFile)
{
    /* Ensure that there is no error and there is least one byte to read. */
    if (   svi2DecFileBufReaderHasError(pBufFile)
        || svi2DecFileBufReaderEnsureData(pBufFile, sizeof(uint64_t)))
        return UINT64_MAX;

    uint64_t u64Val = *(uint64_t *)&pBufFile->abBuf[pBufFile->offBuf];
    pBufFile->offBuf += sizeof(uint64_t);
    return u64Val;
}


/**
 * Resets the given LPC decoder state to the initial state waiting for LFRAME# to be asserted.
 *
 * @returns nothing.
 * @param   pSvi2Dec                The SVI2 decoder state.
 */
static void svi2DecStateReset(PSVI2DEC pSvi2Dec)
{
    pSvi2Dec->idxData  = 0;
    pSvi2Dec->enmState = SVI2DECSTATE_WAIT_START;
}


/**
 * Initializes the given LPC state instance.
 *
 * @returns Status code.
 * @param   pSvi2Dec                The SVI2 decoder state.
 * @param   u8BitSvc                The bit number of the SVC signal in fed samples.
 * @param   u8BitSvd                The bit number of the SVD signal in fed samples.
 */
static int svi2DecStateInit(PSVI2DEC pSvi2Dec, uint8_t u8BitSvc, uint8_t u8BitSvd)
{
    pSvi2Dec->u8BitSvc  = u8BitSvc;
    pSvi2Dec->u8BitSvd  = u8BitSvd;
    pSvi2Dec->fClkLast  = 1; /* We start with a high clock. */
    pSvi2Dec->fSvdLast  = 0;
    svi2DecStateReset(pSvi2Dec);
    return 0;
}


static void svi2DecPktDump(PSVI2DEC pSvi2Dec)
{
    if (   (pSvi2Dec->abData[0] & 0xf8) != 0xc0
        || (pSvi2Dec->abData[0] & 0x1) != 0x0)
        printf("Wrong preamble!\n");
    uint8_t fCore           = !!(pSvi2Dec->abData[0] & 0x4);
    uint8_t fSoc            = !!(pSvi2Dec->abData[0] & 0x2);
    uint8_t fPsi0L          = !!(pSvi2Dec->abData[1] & 0x80);
    uint8_t u8VidCod        = ((pSvi2Dec->abData[1] & 0x7f) << 1) | (pSvi2Dec->abData[2] >> 7);
    uint8_t fPsi1L          = !!(pSvi2Dec->abData[2] & 0x40);
    uint8_t fTfn            = !!(pSvi2Dec->abData[2] & 0x20);
    uint8_t u3LdLnSlopeTrim = pSvi2Dec->abData[2] & 0x1c;
    uint8_t u2OffTrim       = pSvi2Dec->abData[2] & 0x3;

    printf("%016" PRIu64 ": %c%c V=%u.%06uV PSI0=%u PSI1=%u TFN=%u LdLineSlopTrim={%s} OffTrim={%s}\n", pSvi2Dec->uSeqNoCycle,
                         fCore ? 'C' : ' ',
                         fSoc  ? 'S' : ' ',
                         g_au32VidCode2UV[u8VidCod] / 1000000, g_au32VidCode2UV[u8VidCod] % 1000000,
                         fPsi0L, fPsi1L, fTfn,
                         g_apszLdLineSlopeTrim[u3LdLnSlopeTrim],
                         g_apszOffTrim[u2OffTrim]);
}


/**
 * Processes the given sample with the SVI2 decoder state given.
 *
 * @returns Status code.
 * @param   pSvi2Dec                The SVI2 decoder state.
 * @param   uSeqNo                  Sequence number of the sample.
 * @param   bSample                 The new sample to process.
 */
static int svi2DecStateSampleProcess(PSVI2DEC pSvi2Dec, uint64_t uSeqNo, uint8_t bSample)
{
    /* Extract the clock and sample when clock is high. */
    uint8_t fClk = !!(bSample & (1 << pSvi2Dec->u8BitSvc));
    uint8_t fSvd = !!(bSample & (1 << pSvi2Dec->u8BitSvd));
    if (!fClk)
    {
        pSvi2Dec->fClkLast = fClk;
        pSvi2Dec->fSvdLast = fSvd;
        return 0;
    }

    /* If the clock is high and SVD transitions from high to low there is a start condition. */
    if (   fClk == pSvi2Dec->fClkLast
        && !fSvd
        && pSvi2Dec->fSvdLast
        && pSvi2Dec->enmState == SVI2DECSTATE_WAIT_START)
    {
        /* Start condition. */
        pSvi2Dec->enmState    = SVI2DECSTATE_BYTE;
        pSvi2Dec->idxData     = 0;
        pSvi2Dec->cBitsLeft   = 8;
        pSvi2Dec->uSeqNoCycle = uSeqNo;
        memset(&pSvi2Dec->abData[0], 0, sizeof(pSvi2Dec->abData));
    }
    else if (   fClk == pSvi2Dec->fClkLast
             && fSvd
             && !pSvi2Dec->fSvdLast
             && pSvi2Dec->enmState == SVI2DECSTATE_BYTE)
    {
        /* Stop condition. */
        if (pSvi2Dec->idxData != 3)
            printf("Not enough data received!\n");
        else
            svi2DecPktDump(pSvi2Dec);
        pSvi2Dec->enmState = SVI2DECSTATE_WAIT_START;
    }
    else if (pSvi2Dec->enmState != SVI2DECSTATE_WAIT_START)
    {
        /* Sample on risigin edge (data must be stable before the clock rises and throughout the high phase). */
        if (   !pSvi2Dec->fClkLast
            && fClk)
        {
            /* Act according on the current state. */
            switch (pSvi2Dec->enmState)
            {
                case SVI2DECSTATE_BYTE:
                {
                    //if (pSvi2Dec->idxData == 3)
                    //    printf("Too much data!\n");
                    pSvi2Dec->cBitsLeft--;
                    pSvi2Dec->abData[pSvi2Dec->idxData] |= (fSvd << pSvi2Dec->cBitsLeft);
                    if (!pSvi2Dec->cBitsLeft)
                        pSvi2Dec->enmState = SVI2DECSTATE_ACK;
                    break;
                }
                case SVI2DECSTATE_ACK:
                {
                    if (fSvd)
                        printf("Invalid ACK value!\n");
                    if (pSvi2Dec->idxData == 3)
                        printf("Too much data!\n");
                    pSvi2Dec->idxData++;
                    pSvi2Dec->enmState  = SVI2DECSTATE_BYTE;
                    pSvi2Dec->cBitsLeft = 8;
                    break;
                }
                case SVI2DECSTATE_WAIT_START:
                default:
                    printf("Unknown/Invalid state %u\n", pSvi2Dec->enmState);
            }
        }
    }

    pSvi2Dec->fClkLast = fClk;
    pSvi2Dec->fSvdLast = fSvd;
    return 0;
}


int main(int argc, char *argv[])
{
    int ch = 0;
    int idxOption = 0;
    const char *pszFilename = NULL;

    while ((ch = getopt_long (argc, argv, "Hvi:", &g_aOptions[0], &idxOption)) != -1)
    {
        switch (ch)
        {
            case 'h':
            case 'H':
                printf("%s: Low Pin Count Bus protocol decoder\n"
                       "    --input <path/to/saleae/capture>\n"
                       "    --verbose Dumps more information for each cycle like the state transitions encountered\n",
                       argv[0]);
                return 0;
            case 'v':
                g_fVerbose = 1;
                break;
            case 'i':
                pszFilename = optarg;
                break;

            default:
                fprintf(stderr, "Unrecognised option: -%c\n", optopt);
                return 1;
        }
    }

    if (!pszFilename)
    {
        fprintf(stderr, "A filepath to the capture is required!\n");
        return 1;
    }

    PSVI2DECFILEBUFREAD pBufFile = NULL;
    int rc = svi2DecFileBufReaderCreate(&pBufFile, pszFilename);
    if (!rc)
    {
        SVI2DEC Svi2Dec;
        svi2DecStateInit(&Svi2Dec, 0, 1); /** @todo Make configurable */

        while (   !svi2DecFileBufReaderHasEos(pBufFile)
               && !rc)
        {
            uint64_t uSeqNo = svi2DecFileBufReaderGetU64(pBufFile);
            uint8_t bVal = svi2DecFileBufReaderGetU8(pBufFile);
            rc = svi2DecStateSampleProcess(&Svi2Dec, uSeqNo, bVal);
        }

        svi2DecFileBufReaderClose(pBufFile);
    }
    else
        fprintf(stderr, "The file '%s' could not be opened\n", pszFilename);

    return 0;
}

