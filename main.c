#include <stdio.h>
#include <windows.h>

int main(int argc, char *argv[]) {

    if (argc != 2) {
        fprintf(stderr, "ERROR: invalid arguments.");
        return 0;
    }

    FILE *input_file = fopen(argv[1], "rb");
    FILE *output_sections = fopen("..\\sections_inf.txt", "w");
    FILE *output_bin = fopen("..\\bin.txt", "wb");

    if (!input_file || !output_sections || !output_bin) {
        fprintf(stderr, "ERROR: problems with files.");
        return 0;
    }

    IMAGE_DOS_HEADER dos_header = {0};
    IMAGE_NT_HEADERS pe_header = {0};


    if (!fread(&dos_header, sizeof(dos_header), 1, input_file)) { // read DOS header
        fprintf(stderr, "ERROR: dos_header reading problems.");
        return 0;
    }
    if (dos_header.e_magic != IMAGE_DOS_SIGNATURE) {
        fprintf(stderr, "ERROR: invalid file.");
        return 0;
    }

    fseek(input_file, dos_header.e_lfanew, 0); // go to PE Header

    if (!fread(&pe_header, sizeof(pe_header), 1, input_file)) {
        fprintf(stderr, "ERROR: pe_header reading problems.");
        return 0;
    }

    // Print information about number of sections and address of entry point
    fprintf(output_sections, "Number of sections: %d\n", pe_header.FileHeader.NumberOfSections);
    fprintf(output_sections, "Address of entry point: 0x%08*lX\n\n", pe_header.OptionalHeader.AddressOfEntryPoint);

    IMAGE_SECTION_HEADER* sections = malloc(sizeof(IMAGE_SECTION_HEADER) * pe_header.FileHeader.NumberOfSections);

    for (unsigned short i = 0; i < pe_header.FileHeader.NumberOfSections; i++) {
        if (!fread(&(sections[i]), sizeof(IMAGE_SECTION_HEADER), 1, input_file)) {
            fprintf(stderr, "ERROR: sections reading problems.");
            return 0;
        }

        // Print information about section
        fprintf(output_sections, "Name of section: %s\n", sections[i].Name);
        fprintf(output_sections, "Virtual size:\t\t0x%08*lX\n", sections[i].Misc.VirtualSize);
        fprintf(output_sections, "Virtual address:\t0x%08*lX\n", sections[i].VirtualAddress);
        fprintf(output_sections, "Size of raw data:\t0x%08*lX\n", sections[i].SizeOfRawData);
        fprintf(output_sections, "Raw data offset:\t0x%08*lX\n", sections[i].PointerToRawData);
        fprintf(output_sections, "Characteristics:\t0x%08*lX\n", sections[i].Characteristics);



    }

    for (unsigned short i = 0; i < pe_header.FileHeader.NumberOfSections; i++) {
        if ((sections[i].Characteristics % 0x100) == IMAGE_SCN_CNT_CODE) {
            fseek(input_file, sections[i].PointerToRawData, 0);
            char *current_section = malloc(sections[i].SizeOfRawData);
            if (!fread(current_section, sections[i].SizeOfRawData, 1, input_file)) {
                fprintf(stderr, "ERROR: code section reading problems.");
                return 0;
            }
            fwrite(current_section, sections[i].SizeOfRawData, 1, output_bin);
        }

    }


    fclose(input_file);
    fclose(output_sections);
    fclose(output_bin);

    free(sections);

    return 0;
}
